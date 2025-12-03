//==============================================================================
// File: aes256_mixcolumns.v
// Description: MixColumns and InvMixColumns Transformation for AES-256
// - MixColumns: Matrix multiplication in GF(2^8) for encryption
// - InvMixColumns: Inverse matrix multiplication for decryption
// - Operates on 4 columns of state matrix
//==============================================================================

module aes256_mixcolumns (
    input  wire         mode_i,      // 0=Encrypt (MixColumns), 1=Decrypt (InvMixColumns)
    input  wire [127:0] state_i,     // Input state (16 bytes)
    output wire [127:0] state_o      // Output state (16 bytes)
);

    //==========================================================================
    // MIXCOLUMNS MATRIX (for Encryption)
    // [02 03 01 01]
    // [01 02 03 01]
    // [01 01 02 03]
    // [03 01 01 02]
    //==========================================================================

    //==========================================================================
    // INVERSE MIXCOLUMNS MATRIX (for Decryption)
    // [0E 0B 0D 09]
    // [09 0E 0B 0D]
    // [0D 09 0E 0B]
    // [0B 0D 09 0E]
    //==========================================================================

    // Extract 4 columns from input state
    // FIPS-197 byte order: Byte[0]=bit[127:120], Byte[15]=bit[7:0]
    wire [31:0] col0_in, col1_in, col2_in, col3_in;
    assign col0_in = state_i[127: 96];  // Bytes [0:3]   (MSB)
    assign col1_in = state_i[ 95: 64];  // Bytes [4:7]
    assign col2_in = state_i[ 63: 32];  // Bytes [8:11]
    assign col3_in = state_i[ 31:  0];  // Bytes [12:15] (LSB)

    // Output columns after MixColumns
    wire [31:0] col0_out, col1_out, col2_out, col3_out;

    //==========================================================================
    // INSTANTIATE MIXCOLUMN FOR EACH COLUMN
    //==========================================================================
    aes256_mixcolumn mix_col0 (
        .mode_i(mode_i),
        .col_i(col0_in),
        .col_o(col0_out)
    );

    aes256_mixcolumn mix_col1 (
        .mode_i(mode_i),
        .col_i(col1_in),
        .col_o(col1_out)
    );

    aes256_mixcolumn mix_col2 (
        .mode_i(mode_i),
        .col_i(col2_in),
        .col_o(col2_out)
    );

    aes256_mixcolumn mix_col3 (
        .mode_i(mode_i),
        .col_i(col3_in),
        .col_o(col3_out)
    );

    // Pack output state (FIPS-197 byte order)
    assign state_o = {col0_out, col1_out, col2_out, col3_out};

endmodule


//==============================================================================
// SUBMODULE: aes256_mixcolumn (single column)
//==============================================================================
module aes256_mixcolumn (
    input  wire        mode_i,   // 0=Encrypt, 1=Decrypt
    input  wire [31:0] col_i,    // Input column (4 bytes)
    output wire [31:0] col_o     // Output column (4 bytes)
);

    // Extract bytes from input column
    // Column format: Byte[i] at bit[31-i*8:24-i*8]
    wire [7:0] b0, b1, b2, b3;
    assign b0 = col_i[31:24];  // Byte 0 (MSB)
    assign b1 = col_i[23:16];  // Byte 1
    assign b2 = col_i[15: 8];  // Byte 2
    assign b3 = col_i[ 7: 0];  // Byte 3 (LSB)

    //==========================================================================
    // GF(2^8) MULTIPLICATIONS
    //==========================================================================
    
    // For Encryption (MixColumns)
    wire [7:0] b0_x2, b1_x2, b2_x2, b3_x2;  // Multiply by 0x02
    wire [7:0] b0_x3, b1_x3, b2_x3, b3_x3;  // Multiply by 0x03

    gf_mult gf_b0_x2 (.a(b0), .b(8'h02), .product(b0_x2));
    gf_mult gf_b1_x2 (.a(b1), .b(8'h02), .product(b1_x2));
    gf_mult gf_b2_x2 (.a(b2), .b(8'h02), .product(b2_x2));
    gf_mult gf_b3_x2 (.a(b3), .b(8'h02), .product(b3_x2));

    gf_mult gf_b0_x3 (.a(b0), .b(8'h03), .product(b0_x3));
    gf_mult gf_b1_x3 (.a(b1), .b(8'h03), .product(b1_x3));
    gf_mult gf_b2_x3 (.a(b2), .b(8'h03), .product(b2_x3));
    gf_mult gf_b3_x3 (.a(b3), .b(8'h03), .product(b3_x3));

    // For Decryption (InvMixColumns)
    wire [7:0] b0_x9, b1_x9, b2_x9, b3_x9;   // Multiply by 0x09
    wire [7:0] b0_xB, b1_xB, b2_xB, b3_xB;   // Multiply by 0x0B
    wire [7:0] b0_xD, b1_xD, b2_xD, b3_xD;   // Multiply by 0x0D
    wire [7:0] b0_xE, b1_xE, b2_xE, b3_xE;   // Multiply by 0x0E

    gf_mult gf_b0_x9 (.a(b0), .b(8'h09), .product(b0_x9));
    gf_mult gf_b1_x9 (.a(b1), .b(8'h09), .product(b1_x9));
    gf_mult gf_b2_x9 (.a(b2), .b(8'h09), .product(b2_x9));
    gf_mult gf_b3_x9 (.a(b3), .b(8'h09), .product(b3_x9));

    gf_mult gf_b0_xB (.a(b0), .b(8'h0B), .product(b0_xB));
    gf_mult gf_b1_xB (.a(b1), .b(8'h0B), .product(b1_xB));
    gf_mult gf_b2_xB (.a(b2), .b(8'h0B), .product(b2_xB));
    gf_mult gf_b3_xB (.a(b3), .b(8'h0B), .product(b3_xB));

    gf_mult gf_b0_xD (.a(b0), .b(8'h0D), .product(b0_xD));
    gf_mult gf_b1_xD (.a(b1), .b(8'h0D), .product(b1_xD));
    gf_mult gf_b2_xD (.a(b2), .b(8'h0D), .product(b2_xD));
    gf_mult gf_b3_xD (.a(b3), .b(8'h0D), .product(b3_xD));

    gf_mult gf_b0_xE (.a(b0), .b(8'h0E), .product(b0_xE));
    gf_mult gf_b1_xE (.a(b1), .b(8'h0E), .product(b1_xE));
    gf_mult gf_b2_xE (.a(b2), .b(8'h0E), .product(b2_xE));
    gf_mult gf_b3_xE (.a(b3), .b(8'h0E), .product(b3_xE));

    //==========================================================================
    // MATRIX MULTIPLICATION
    //==========================================================================
    
    wire [7:0] r0, r1, r2, r3;  // Result bytes

    // MixColumns (Encryption mode)
    wire [7:0] r0_enc = b0_x2 ^ b1_x3 ^ b2    ^ b3;
    wire [7:0] r1_enc = b0    ^ b1_x2 ^ b2_x3 ^ b3;
    wire [7:0] r2_enc = b0    ^ b1    ^ b2_x2 ^ b3_x3;
    wire [7:0] r3_enc = b0_x3 ^ b1    ^ b2    ^ b3_x2;

    // InvMixColumns (Decryption mode)
    wire [7:0] r0_dec = b0_xE ^ b1_xB ^ b2_xD ^ b3_x9;
    wire [7:0] r1_dec = b0_x9 ^ b1_xE ^ b2_xB ^ b3_xD;
    wire [7:0] r2_dec = b0_xD ^ b1_x9 ^ b2_xE ^ b3_xB;
    wire [7:0] r3_dec = b0_xB ^ b1_xD ^ b2_x9 ^ b3_xE;

    // Select based on mode
    assign r0 = mode_i ? r0_dec : r0_enc;
    assign r1 = mode_i ? r1_dec : r1_enc;
    assign r2 = mode_i ? r2_dec : r2_enc;
    assign r3 = mode_i ? r3_dec : r3_enc;

    // Pack output column (FIPS-197 byte order: Byte[0] at MSB)
    assign col_o = {r0, r1, r2, r3};

endmodule
