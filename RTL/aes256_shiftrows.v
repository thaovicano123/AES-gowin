//==============================================================================
// File: aes256_shiftrows.v
// Description: ShiftRows and InvShiftRows Transformation for AES-256
// - Row 0: no shift
// - Row 1: shift left/right 1 position
// - Row 2: shift left/right 2 positions
// - Row 3: shift left/right 3 positions
// - Combinational logic (no registers)
//==============================================================================

module aes256_shiftrows (
    input  wire         mode_i,      // 0=Encrypt (shift left), 1=Decrypt (shift right)
    input  wire [127:0] state_i,     // Input state (16 bytes)
    output wire [127:0] state_o      // Output state (16 bytes)
);

    //==========================================================================
    // STATE ORGANIZATION (Column-major order)
    // FIPS-197 byte order: Byte[0] at MSB (bit[127:120])
    // state_i[127:0] organized as:
    //   Byte  0 =  s[0][0]  |  Byte  4 =  s[0][1]  |  Byte  8 =  s[0][2]  |  Byte 12 =  s[0][3]
    //   Byte  1 =  s[1][0]  |  Byte  5 =  s[1][1]  |  Byte  9 =  s[1][2]  |  Byte 13 =  s[1][3]
    //   Byte  2 =  s[2][0]  |  Byte  6 =  s[2][1]  |  Byte 10 =  s[2][2]  |  Byte 14 =  s[2][3]
    //   Byte  3 =  s[3][0]  |  Byte  7 =  s[3][1]  |  Byte 11 =  s[3][2]  |  Byte 15 =  s[3][3]
    //==========================================================================

    // Extract bytes from input state
    wire [7:0] s00, s01, s02, s03;  // Row 0
    wire [7:0] s10, s11, s12, s13;  // Row 1
    wire [7:0] s20, s21, s22, s23;  // Row 2
    wire [7:0] s30, s31, s32, s33;  // Row 3

    // FIPS-197 byte order: Byte[0]=bit[127:120], Byte[15]=bit[7:0]
    assign s00 = state_i[127:120];  assign s01 = state_i[ 95: 88];
    assign s02 = state_i[ 63: 56];  assign s03 = state_i[ 31: 24];
    
    assign s10 = state_i[119:112];  assign s11 = state_i[ 87: 80];
    assign s12 = state_i[ 55: 48];  assign s13 = state_i[ 23: 16];
    
    assign s20 = state_i[111:104];  assign s21 = state_i[ 79: 72];
    assign s22 = state_i[ 47: 40];  assign s23 = state_i[ 15:  8];
    
    assign s30 = state_i[103: 96];  assign s31 = state_i[ 71: 64];
    assign s32 = state_i[ 39: 32];  assign s33 = state_i[  7:  0];

    //==========================================================================
    // SHIFTROWS TRANSFORMATION
    //==========================================================================
    // Encryption (mode_i=0): Shift Left
    //   Row 0: no shift         [s00, s01, s02, s03]
    //   Row 1: shift left 1     [s11, s12, s13, s10]
    //   Row 2: shift left 2     [s22, s23, s20, s21]
    //   Row 3: shift left 3     [s33, s30, s31, s32]
    //
    // Decryption (mode_i=1): Shift Right
    //   Row 0: no shift         [s00, s01, s02, s03]
    //   Row 1: shift right 1    [s13, s10, s11, s12]
    //   Row 2: shift right 2    [s22, s23, s20, s21]  (same as left 2)
    //   Row 3: shift right 3    [s31, s32, s33, s30]
    //==========================================================================

    wire [7:0] r00, r01, r02, r03;  // Output Row 0
    wire [7:0] r10, r11, r12, r13;  // Output Row 1
    wire [7:0] r20, r21, r22, r23;  // Output Row 2
    wire [7:0] r30, r31, r32, r33;  // Output Row 3

    // Row 0: no shift
    assign r00 = s00;
    assign r01 = s01;
    assign r02 = s02;
    assign r03 = s03;

    // Row 1: shift left 1 (encrypt) or shift right 1 (decrypt)
    assign r10 = mode_i ? s13 : s11;
    assign r11 = mode_i ? s10 : s12;
    assign r12 = mode_i ? s11 : s13;
    assign r13 = mode_i ? s12 : s10;

    // Row 2: shift left 2 or right 2 (same result)
    assign r20 = s22;
    assign r21 = s23;
    assign r22 = s20;
    assign r23 = s21;

    // Row 3: shift left 3 (encrypt) or shift right 3 (decrypt)
    assign r30 = mode_i ? s31 : s33;
    assign r31 = mode_i ? s32 : s30;
    assign r32 = mode_i ? s33 : s31;
    assign r33 = mode_i ? s30 : s32;

    // Pack output state (column-major order, FIPS-197 byte order)
    // Byte[0]=bit[127:120], Byte[1]=bit[119:112], ..., Byte[15]=bit[7:0]
    assign state_o = {
        r00, r10, r20, r30,  // Bytes 0,1,2,3     (Column 0)
        r01, r11, r21, r31,  // Bytes 4,5,6,7     (Column 1)
        r02, r12, r22, r32,  // Bytes 8,9,10,11   (Column 2)
        r03, r13, r23, r33   // Bytes 12,13,14,15 (Column 3)
    };

endmodule
